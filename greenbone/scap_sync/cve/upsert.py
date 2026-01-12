from itertools import chain
from typing import (
    Sequence,
)
from uuid import uuid4

from pontos.nvd.models.cve import CVE
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import Insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from greenbone.scap.cve.models import (
    ConfigurationModel,
    CPEMatchModel,
    CVEDescriptionModel,
    CVEModel,
    CVSSv2MetricModel,
    CVSSv3MetricModel,
    NodeModel,
    ReferenceModel,
    VendorCommentModel,
    WeaknessDescriptionModel,
    WeaknessModel,
)


async def upsert_cves(db: AsyncEngine, cves: Sequence[CVE]) -> None:
    if not cves:
        return

    async with db.begin() as tx:
        await _upsert_cves(tx, cves)

        await _upsert_cve_descriptions(tx, cves)
        await _upsert_references(tx, cves)
        await _upsert_weaknesses(tx, cves)
        await _upsert_weakness_descriptions(tx, cves)
        await _upsert_comments(tx, cves)
        await _upsert_configurations(tx, cves)
        await _upsert_cvss_v2(tx, cves)
        await _upsert_cvss_v3(tx, cves)


async def _upsert_cves(conn: AsyncConnection, cves: Sequence[CVE]) -> None:
    dbCVEs = [
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
    ]

    statement = Insert(CVEModel)
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

    await conn.execute(statement, dbCVEs)


async def _upsert_cvss_v2(conn: AsyncConnection, cves: Sequence[CVE]) -> None:
    cvss_v2_statement = Insert(CVSSv2MetricModel).execution_options(
        render_nulls=True
    )

    cvss_v2_data = []
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

    delete_statement = delete(CVSSv2MetricModel).where(
        CVSSv2MetricModel.cve_id.in_(cve_ids)
    )

    await conn.execute(delete_statement)

    if cvss_v2_data:
        await conn.execute(cvss_v2_statement, cvss_v2_data)


async def _upsert_cvss_v3(conn: AsyncConnection, cves: Sequence[CVE]) -> None:
    cvss_v3_statement = Insert(CVSSv3MetricModel).execution_options(
        render_nulls=True
    )

    cvss_v3_data = []
    cve_ids: list[str] = []

    for cve in cves:
        cve_ids.append(cve.id)

        if not cve.metrics:
            continue

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

    delete_statement = delete(CVSSv3MetricModel).where(
        CVSSv3MetricModel.cve_id.in_(cve_ids)
    )

    await conn.execute(delete_statement)

    if cvss_v3_data:
        await conn.execute(cvss_v3_statement, cvss_v3_data)


async def _upsert_cve_descriptions(
    connection: AsyncConnection, cves: Sequence[CVE]
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

    if not cve_descriptions:
        return

    statement = Insert(CVEDescriptionModel).execution_options(render_nulls=True)
    statement = statement.on_conflict_do_update(
        index_elements=[
            CVEDescriptionModel.cve_id,
            CVEDescriptionModel.lang,
        ],
        set_=dict(
            cve_id=statement.excluded.cve_id,
            lang=statement.excluded.lang,
            value=statement.excluded.value,
        ),
    )

    await connection.execute(statement, cve_descriptions)


async def _upsert_references(
    connection: AsyncConnection, cves: Sequence[CVE]
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

    if not references:
        return

    statement = Insert(ReferenceModel).execution_options(render_nulls=True)
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

    await connection.execute(statement, references)


async def _upsert_weaknesses(
    connection: AsyncConnection, cves: Sequence[CVE]
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

    if not weaknesses:
        return

    statement = Insert(WeaknessModel).execution_options(render_nulls=True)
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

    await connection.execute(statement, weaknesses)


async def _upsert_weakness_descriptions(
    connection: AsyncConnection, cves: Sequence[CVE]
) -> None:
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

    if not weakness_descriptions:
        return

    statement = Insert(WeaknessDescriptionModel).execution_options(
        render_nulls=True
    )
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

    await connection.execute(statement, weakness_descriptions)


async def _upsert_comments(
    connection: AsyncConnection, cves: Sequence[CVE]
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

    if not comments:
        return

    statement = Insert(VendorCommentModel).execution_options(render_nulls=True)
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

    await connection.execute(statement, comments)


async def _upsert_configurations(
    connection: AsyncConnection, cves: Sequence[CVE]
) -> None:
    cve_ids = []
    configurations = []
    matches = []
    nodes = []

    for cve in cves:
        cve_ids.append(cve.id)

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

    delete_statement = delete(ConfigurationModel).where(
        ConfigurationModel.cve_id.in_(cve_ids)
    )
    await connection.execute(delete_statement)

    if configurations:
        configuration_statement = Insert(ConfigurationModel)
        await connection.execute(configuration_statement, configurations)
    if nodes:
        node_statement = Insert(NodeModel)
        await connection.execute(node_statement, nodes)
    if matches:
        match_statement = Insert(CPEMatchModel)
        await connection.execute(match_statement, matches)


__all__ = ["upsert_cves"]
