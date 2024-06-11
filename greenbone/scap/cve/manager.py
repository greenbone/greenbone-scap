# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import asynccontextmanager
from datetime import datetime
from itertools import chain
from types import TracebackType
from typing import (
    AsyncContextManager,
    AsyncGenerator,
    AsyncIterator,
    Iterable,
    Self,
    Sequence,
)
from uuid import uuid4

from pontos.nvd.models.cve import CVE
from sqlalchemy import ColumnElement, and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import selectinload

from greenbone.scap.db import Database

from .models import (
    Base,
    ConfigurationModel,
    CPEMatchModel,
    CVEDescriptionModel,
    CVEModel,
    CVSSv2MetricModel,
    CVSSv3MetricModel,
    NodeModel,
    ReferenceModel,
    VendorCommentModel,
    VulnStatus,
    WeaknessDescriptionModel,
    WeaknessModel,
)

DEFAULT_THRESHOLD = 100
DEFAULT_YIELD_PER = 100


class CVEManager(AsyncContextManager):
    def __init__(
        self,
        db: Database,
        *,
        insert_threshold: int = DEFAULT_THRESHOLD,
        yield_per: int = DEFAULT_YIELD_PER,
        update: bool = True,
    ) -> None:
        self._db = db
        self._cves: list[CVE] = []
        self._insert_threshold = insert_threshold
        self._update = update
        self._yield_per = yield_per

    async def __aenter__(self) -> Self:
        await self._db.init(Base.metadata.create_all)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if not exc_type:
            # not an error
            await self.add_cves(self._cves)
        return

    async def add(self, cve: CVE) -> None:
        self._cves.append(cve)

        if len(self._cves) > self._insert_threshold:
            await self.add_cves(self._cves)

    async def add_cves(self, cves: Sequence[CVE]) -> None:
        if not cves:
            return

        statement = self._db.insert(CVEModel)

        if self._update:
            statement = statement.on_conflict_do_update(
                index_elements=[CVEModel.id],
                set_=dict(
                    id=statement.excluded.id,
                    source_identifier=statement.excluded.source_identifier,
                    published=statement.excluded.published,
                    last_modified=statement.excluded.last_modified,
                    vuln_status=statement.excluded.vuln_status,
                    evaluator_comment=statement.excluded.evaluator_comment,
                    evaluator_solution=statement.excluded.evaluator_solution,
                    evaluator_impact=statement.excluded.evaluator_impact,
                    cisa_exploit_add=statement.excluded.cisa_exploit_add,
                    cisa_action_due=statement.excluded.cisa_action_due,
                    cisa_required_action=statement.excluded.cisa_required_action,
                    cisa_vulnerability_name=statement.excluded.cisa_vulnerability_name,
                ),
            )
        else:
            statement = statement.on_conflict_do_nothing()

        async with self._db.transaction() as transaction:
            await transaction.execute(
                statement,
                [
                    dict(
                        id=cve.id,
                        source_identifier=cve.source_identifier,
                        published=cve.published,
                        last_modified=cve.last_modified,
                        vuln_status=cve.vuln_status,
                        evaluator_comment=cve.evaluator_comment,
                        evaluator_solution=cve.evaluator_solution,
                        evaluator_impact=cve.evaluator_impact,
                        cisa_exploit_add=cve.cisa_exploit_add,
                        cisa_action_due=cve.cisa_action_due,
                        cisa_required_action=cve.cisa_required_action,
                        cisa_vulnerability_name=cve.cisa_vulnerability_name,
                    )
                    for cve in cves
                ],
            )

            await self._insert_foreign_data(transaction, cves)

        self._cves = []

    async def _insert_foreign_data(
        self, connection: AsyncConnection, cves: Sequence[CVE]
    ) -> None:
        await self._insert_cve_descriptions(connection, cves)
        await self._insert_references(connection, cves)
        await self._insert_weaknesses(connection, cves)
        await self._insert_comments(connection, cves)
        await self._insert_configurations(connection, cves)
        await self._insert_cvss(connection, cves)

    async def _insert_cvss(
        self, connection: AsyncConnection, cves: Sequence[CVE]
    ) -> None:
        cvss_v2_statement = self._db.insert(
            CVSSv2MetricModel
        ).execution_options(render_nulls=True)
        cvss_v3_statement = self._db.insert(
            CVSSv3MetricModel
        ).execution_options(render_nulls=True)

        cvss_v2_data = []
        cvss_v3_data = []
        cve_ids: list[str] = []

        for cve in cves:
            cve_ids.append(cve.id)

            if not cve.metrics:
                continue

            cvss_v2_data.extend(
                [
                    dict(
                        cve_id=cve.id,
                        source=cvss_v2.source,
                        type=cvss_v2.type,
                        base_severity=cvss_v2.base_severity,
                        exploitability_score=cvss_v2.exploitability_score,
                        impact_score=cvss_v2.impact_score,
                        ac_insuf_info=cvss_v2.ac_insuf_info,
                        obtain_all_privilege=cvss_v2.obtain_all_privilege,
                        obtain_user_privilege=cvss_v2.obtain_user_privilege,
                        obtain_other_privilege=cvss_v2.obtain_other_privilege,
                        user_interaction_required=cvss_v2.user_interaction_required,
                        vector_string=cvss_v2.cvss_data.vector_string,
                        version=cvss_v2.cvss_data.version,
                        base_score=cvss_v2.cvss_data.base_score,
                        access_vector=cvss_v2.cvss_data.access_vector,
                        access_complexity=cvss_v2.cvss_data.access_complexity,
                        authentication=cvss_v2.cvss_data.authentication,
                        confidentiality_impact=cvss_v2.cvss_data.confidentiality_impact,
                        integrity_impact=cvss_v2.cvss_data.integrity_impact,
                        availability_impact=cvss_v2.cvss_data.availability_impact,
                        exploitability=cvss_v2.cvss_data.exploitability,
                        remediation_level=cvss_v2.cvss_data.remediation_level,
                        report_confidence=cvss_v2.cvss_data.report_confidence,
                        temporal_score=cvss_v2.cvss_data.temporal_score,
                        collateral_damage_potential=cvss_v2.cvss_data.collateral_damage_potential,
                        target_distribution=cvss_v2.cvss_data.target_distribution,
                        confidentiality_requirement=cvss_v2.cvss_data.confidentiality_requirement,
                        integrity_requirement=cvss_v2.cvss_data.integrity_requirement,
                        availability_requirement=cvss_v2.cvss_data.availability_requirement,
                        environmental_score=cvss_v2.cvss_data.environmental_score,
                    )
                    for cvss_v2 in cve.metrics.cvss_metric_v2
                ]
            )

            cvss_v3_data.extend(
                [
                    dict(
                        cve_id=cve.id,
                        source=cvss_v3.source,
                        type=cvss_v3.type,
                        exploitability_score=cvss_v3.exploitability_score,
                        impact_score=cvss_v3.impact_score,
                        vector_string=cvss_v3.cvss_data.vector_string,
                        version=cvss_v3.cvss_data.version,
                        base_score=cvss_v3.cvss_data.base_score,
                        base_severity=cvss_v3.cvss_data.base_severity,
                        attack_vector=cvss_v3.cvss_data.attack_vector,
                        attack_complexity=cvss_v3.cvss_data.attack_complexity,
                        privileges_required=cvss_v3.cvss_data.privileges_required,
                        user_interaction=cvss_v3.cvss_data.user_interaction,
                        scope=cvss_v3.cvss_data.scope,
                        confidentiality_impact=cvss_v3.cvss_data.confidentiality_impact,
                        integrity_impact=cvss_v3.cvss_data.integrity_impact,
                        availability_impact=cvss_v3.cvss_data.availability_impact,
                        exploit_code_maturity=cvss_v3.cvss_data.exploit_code_maturity,
                        remediation_level=cvss_v3.cvss_data.remediation_level,
                        report_confidence=cvss_v3.cvss_data.report_confidence,
                        temporal_score=cvss_v3.cvss_data.temporal_score,
                        temporal_severity=cvss_v3.cvss_data.temporal_severity,
                        confidentiality_requirement=cvss_v3.cvss_data.confidentiality_requirement,
                        integrity_requirement=cvss_v3.cvss_data.integrity_requirement,
                        availability_requirement=cvss_v3.cvss_data.availability_requirement,
                        modified_attack_vector=cvss_v3.cvss_data.modified_attack_vector,
                        modified_attack_complexity=cvss_v3.cvss_data.modified_attack_complexity,
                        modified_privileges_required=cvss_v3.cvss_data.modified_privileges_required,
                        modified_user_interaction=cvss_v3.cvss_data.modified_user_interaction,
                        modified_scope=cvss_v3.cvss_data.modified_scope,
                        modified_confidentiality_impact=cvss_v3.cvss_data.modified_confidentiality_impact,
                        modified_integrity_impact=cvss_v3.cvss_data.modified_integrity_impact,
                        modified_availability_impact=cvss_v3.cvss_data.modified_availability_impact,
                        environmental_score=cvss_v3.cvss_data.environmental_score,
                        environmental_severity=cvss_v3.cvss_data.environmental_severity,
                    )
                    for cvss_v3 in chain(
                        cve.metrics.cvss_metric_v30,
                        cve.metrics.cvss_metric_v31,
                    )
                ]
            )

        delete_statement = delete(CVSSv2MetricModel).where(
            CVSSv2MetricModel.cve_id.in_(cve_ids)
        )

        await connection.execute(delete_statement)

        delete_statement = delete(CVSSv3MetricModel).where(
            CVSSv3MetricModel.cve_id.in_(cve_ids)
        )

        await connection.execute(delete_statement)

        if cvss_v2_data:
            await connection.execute(cvss_v2_statement, cvss_v2_data)

        if cvss_v3_data:
            await connection.execute(cvss_v3_statement, cvss_v3_data)

    async def _insert_cve_descriptions(
        self, connection: AsyncConnection, cves: Sequence[CVE]
    ) -> None:
        cve_descriptions = [
            dict(
                cve_id=cve.id,
                lang=description.lang,
                value=description.value,
            )
            for cve in cves
            for description in cve.descriptions
        ]
        if cve_descriptions:
            statement = self._db.insert(CVEDescriptionModel).execution_options(
                render_nulls=True
            )

            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[
                        CVEDescriptionModel.cve_id,
                        CVEDescriptionModel.lang,
                        CVEDescriptionModel.value,
                    ],
                    set_=dict(
                        cve_id=statement.excluded.cve_id,
                        lang=statement.excluded.lang,
                        value=statement.excluded.value,
                    ),
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, cve_descriptions)

    async def _insert_references(
        self, connection: AsyncConnection, cves: Sequence[CVE]
    ) -> None:
        references = [
            dict(
                cve_id=cve.id,
                url=reference.url,
                source=reference.source,
                tags=reference.tags,
            )
            for cve in cves
            for reference in cve.references
        ]
        if references:
            statement = self._db.insert(ReferenceModel).execution_options(
                render_nulls=True
            )

            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[
                        ReferenceModel.cve_id,
                        ReferenceModel.url,
                    ],
                    set_=dict(
                        cve_id=statement.excluded.cve_id,
                        url=statement.excluded.url,
                        source=statement.excluded.source,
                        tags=statement.excluded.tags,
                    ),
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, references)

    async def _insert_weaknesses(
        self, connection: AsyncConnection, cves: Sequence[CVE]
    ) -> None:
        weaknesses = [
            dict(
                cve_id=cve.id,
                source=weakness.source,
                type=weakness.type,
            )
            for cve in cves
            for weakness in cve.weaknesses
        ]
        if weaknesses:
            statement = self._db.insert(WeaknessModel).execution_options(
                render_nulls=True
            )

            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[
                        WeaknessModel.cve_id,
                        WeaknessModel.source,
                        WeaknessModel.type,
                    ],
                    set_=dict(
                        cve_id=statement.excluded.cve_id,
                        source=statement.excluded.source,
                        type=statement.excluded.type,
                    ),
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, weaknesses)

            weakness_descriptions = [
                dict(
                    cve_id=cve.id,
                    source=weakness.source,
                    type=weakness.type,
                    lang=description.lang,
                    value=description.value,
                )
                for cve in cves
                for weakness in cve.weaknesses
                for description in weakness.description
            ]

            if weakness_descriptions:
                statement = self._db.insert(
                    WeaknessDescriptionModel
                ).execution_options(render_nulls=True)

                if self._update:
                    statement = statement.on_conflict_do_update(
                        index_elements=[
                            WeaknessDescriptionModel.cve_id,
                            WeaknessDescriptionModel.source,
                            WeaknessDescriptionModel.type,
                            WeaknessDescriptionModel.lang,
                            WeaknessDescriptionModel.value,
                        ],
                        set_=dict(
                            source=statement.excluded.source,
                            type=statement.excluded.type,
                            lang=statement.excluded.lang,
                            value=statement.excluded.value,
                        ),
                    )
                else:
                    statement = statement.on_conflict_do_nothing()

                await connection.execute(statement, weakness_descriptions)

    async def _insert_comments(
        self, connection: AsyncConnection, cves: Sequence[CVE]
    ) -> None:
        comments = [
            dict(
                cve_id=cve.id,
                organization=comment.organization,
                comment=comment.comment,
                last_modified=comment.last_modified,
            )
            for cve in cves
            for comment in cve.vendor_comments
        ]
        if comments:
            statement = self._db.insert(VendorCommentModel).execution_options(
                render_nulls=True
            )

            if self._update:
                statement = statement.on_conflict_do_update(
                    index_elements=[
                        VendorCommentModel.cve_id,
                        VendorCommentModel.organization,
                    ],
                    set_=dict(
                        cve_id=statement.excluded.cve_id,
                        organization=statement.excluded.organization,
                        comment=statement.excluded.comment,
                        last_modified=statement.excluded.last_modified,
                    ),
                )
            else:
                statement = statement.on_conflict_do_nothing()

            await connection.execute(statement, comments)

    async def _insert_configurations(
        self, connection: AsyncConnection, cves: Sequence[CVE]
    ) -> None:
        cve_ids = [cve.id for cve in cves]

        delete_statement = delete(ConfigurationModel).where(
            ConfigurationModel.cve_id.in_(cve_ids)
        )

        await connection.execute(delete_statement)

        configuration_statement = self._db.insert(ConfigurationModel)
        node_statement = self._db.insert(NodeModel)
        match_statement = self._db.insert(CPEMatchModel)

        configurations = []
        matches = []
        nodes = []

        for cve in cves:
            if not cve.configurations:
                continue

            for configuration in cve.configurations:
                configuration_id = uuid4()
                configurations.append(
                    dict(
                        id=configuration_id,
                        cve_id=cve.id,
                        operator=configuration.operator,
                        negate=configuration.negate,
                    )
                )

                if not configuration.nodes:
                    continue

                for node in configuration.nodes:
                    node_id = uuid4()
                    nodes.append(
                        dict(
                            id=node_id,
                            configuration_id=configuration_id,
                            operator=node.operator,
                            negate=node.negate,
                        )
                    )

                    if not node.cpe_match:
                        continue

                    matches.extend(
                        [
                            dict(
                                node_id=node_id,
                                match_criteria_id=match.match_criteria_id,
                                vulnerable=match.vulnerable,
                                criteria=match.criteria,
                                version_start_excluding=match.version_start_excluding,
                                version_start_including=match.version_start_including,
                                version_end_excluding=match.version_end_excluding,
                                version_end_including=match.version_end_including,
                            )
                            for match in node.cpe_match
                        ]
                    )

        if configurations:
            await connection.execute(configuration_statement, configurations)
        if nodes:
            await connection.execute(node_statement, nodes)
        if matches:
            await connection.execute(match_statement, matches)

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self._db.session() as session, session.begin():
            yield session

    def _get_clauses(
        self,
        *,
        cve_ids: Iterable[str] | str | None = None,
        last_modification_start_date: datetime | None = None,
        last_modification_end_date: datetime | None = None,
        published_start_date: datetime | None = None,
        published_end_date: datetime | None = None,
        source_identifier: str | None = None,
        no_rejected: bool = False,
        keywords: Iterable[str] | str | None = None,
        cwe_id: str | None = None,
        cvss_v2_vector: str | None = None,
        cvss_v3_vector: str | None = None,
        cvss_v2_severity: str | None = None,
        cvss_v3_severity: str | None = None,
    ) -> list[ColumnElement[bool]]:
        clauses: list[ColumnElement[bool]] = []
        if cve_ids:
            if isinstance(cve_ids, str):
                cve_ids = (cve_ids,)
            clauses.append(CVEModel.id.in_(cve_ids))
        if last_modification_start_date:
            clauses.append(
                CVEModel.last_modified >= last_modification_start_date
            )
        if last_modification_end_date:
            clauses.append(CVEModel.last_modified <= last_modification_end_date)
        if published_start_date:
            clauses.append(CVEModel.published >= published_start_date)
        if published_end_date:
            clauses.append(CVEModel.published <= published_end_date)
        if source_identifier:
            clauses.append(CVEModel.source_identifier == source_identifier)
        if no_rejected:
            clauses.append(CVEModel.vuln_status != VulnStatus.REJECTED)
        if keywords:
            if isinstance(keywords, str):
                keywords = [keywords]
            ands = [
                CVEModel.descriptions.any(
                    CVEDescriptionModel.value.regexp_match(
                        f"(^| ){keyword}.*", "i"
                    )
                )
                for keyword in keywords
            ]
            clauses.append(and_(*ands))
        if cwe_id:
            clauses.append(
                CVEModel.weaknesses.any(
                    WeaknessModel.description.any(
                        WeaknessDescriptionModel.value == cwe_id
                    )
                )
            )
        if cvss_v2_vector:
            clauses.append(
                CVEModel.cvss_metrics_v2.any(
                    CVSSv2MetricModel.vector_string.ilike(f"%{cvss_v2_vector}%")
                )
            )
        if cvss_v3_vector:
            clauses.append(
                CVEModel.cvss_metrics_v3.any(
                    CVSSv3MetricModel.vector_string.ilike(f"%{cvss_v3_vector}%")
                )
            )
        if cvss_v2_severity:
            clauses.append(
                CVEModel.cvss_metrics_v2.any(
                    CVSSv3MetricModel.base_severity == cvss_v2_severity.upper()
                )
            )
        if cvss_v3_severity:
            clauses.append(
                CVEModel.cvss_metrics_v3.any(
                    CVSSv3MetricModel.base_severity == cvss_v3_severity.upper()
                )
            )
        return clauses

    async def find(
        self,
        *,
        cve_ids: Iterable[str] | str | None = None,
        limit: int | None = None,
        index: int | None = None,
        last_modification_start_date: datetime | None = None,
        last_modification_end_date: datetime | None = None,
        published_start_date: datetime | None = None,
        published_end_date: datetime | None = None,
        source_identifier: str | None = None,
        no_rejected: bool = False,
        keywords: Iterable[str] | str | None = None,
        cwe_id: str | None = None,
        cvss_v2_vector: str | None = None,
        cvss_v3_vector: str | None = None,
        cvss_v2_severity: str | None = None,
        cvss_v3_severity: str | None = None,
    ) -> AsyncIterator[CVEModel]:
        clauses = self._get_clauses(
            cve_ids=cve_ids,
            last_modification_start_date=last_modification_start_date,
            last_modification_end_date=last_modification_end_date,
            published_start_date=published_start_date,
            published_end_date=published_end_date,
            source_identifier=source_identifier,
            no_rejected=no_rejected,
            keywords=keywords,
            cwe_id=cwe_id,
            cvss_v2_vector=cvss_v2_vector,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_severity=cvss_v2_severity,
            cvss_v3_severity=cvss_v3_severity,
        )
        statement = (
            select(CVEModel)
            .options(
                selectinload(CVEModel.cvss_metrics_v2),
                selectinload(CVEModel.cvss_metrics_v3),
                selectinload(CVEModel.cvss_metrics_v30),
                selectinload(CVEModel.cvss_metrics_v31),
                selectinload(CVEModel.configurations)
                .selectinload(ConfigurationModel.nodes)
                .selectinload(NodeModel.cpe_match),
                selectinload(CVEModel.descriptions),
                selectinload(CVEModel.references),
                selectinload(CVEModel.vendor_comments),
                selectinload(CVEModel.weaknesses).selectinload(
                    WeaknessModel.description
                ),
            )
            .where(*clauses)
            .order_by(CVEModel.id)
            .limit(limit)
            .execution_options(yield_per=self._yield_per)
        )

        if index is not None:
            statement = statement.offset(index)

        async with self.session() as session:
            result = await session.stream_scalars(statement)
            async for cpe_model in result:
                yield cpe_model

    def all(self) -> AsyncIterator[CVEModel]:
        return self.find()

    async def count(
        self,
        *,
        cve_ids: Iterable[str] | str | None = None,
        last_modification_start_date: datetime | None = None,
        last_modification_end_date: datetime | None = None,
        published_start_date: datetime | None = None,
        published_end_date: datetime | None = None,
        source_identifier: str | None = None,
        no_rejected: bool = False,
        keywords: Iterable[str] | str | None = None,
        cwe_id: str | None = None,
        cvss_v2_vector: str | None = None,
        cvss_v3_vector: str | None = None,
        cvss_v2_severity: str | None = None,
        cvss_v3_severity: str | None = None,
    ) -> int:
        clauses = self._get_clauses(
            cve_ids=cve_ids,
            last_modification_start_date=last_modification_start_date,
            last_modification_end_date=last_modification_end_date,
            published_start_date=published_start_date,
            published_end_date=published_end_date,
            source_identifier=source_identifier,
            no_rejected=no_rejected,
            keywords=keywords,
            cwe_id=cwe_id,
            cvss_v2_vector=cvss_v2_vector,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_severity=cvss_v2_severity,
            cvss_v3_severity=cvss_v3_severity,
        )

        statement = select(func.count(CVEModel.id)).where(*clauses)
        async with self._db.transaction() as transaction:
            result = await transaction.execute(statement)
            return result.scalar()  # type: ignore[return-value]
