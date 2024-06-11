# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    String,
    TypeDecorator,
    Uuid,
    and_,
)
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(AsyncAttrs, DeclarativeBase):
    type_annotation_map = {
        datetime: DateTime(timezone=True),
    }

    def __repr__(self) -> str:
        repr_string = ", ".join(
            [
                f"{key}={value!r}"
                for key, value in self.__dict__.items()
                if not key.startswith("_")
            ]
        )
        return f"{self.__class__.__name__}({repr_string})"


cve_pk = Annotated[str, mapped_column(String(20), primary_key=True)]
cve_fk = Annotated[
    str, mapped_column(ForeignKey("cves.id", ondelete="CASCADE"))
]


class StrListType(TypeDecorator):
    impl = String

    def process_bind_param(self, value: list[str], dialect) -> str:  # type: ignore[override]
        return ",".join(value)

    def process_result_value(self, value: str, dialect) -> list[str]:  # type: ignore[override]
        return value.split(",") if value else []


class VulnStatus(StrEnum):
    REJECTED = "Rejected"
    ANALYZED = "Analyzed"
    AWAITING_ANALYSIS = "Awaiting Analysis"
    MODIFIED = "Modified"
    RECEIVED = "Received"
    Rejected = "Rejected"
    UNDERGOING_ANALYSIS = "Undergoing Analysis"


class CVEModel(Base):
    __tablename__ = "cves"

    id: Mapped[cve_pk]
    source_identifier: Mapped[str]
    published: Mapped[datetime]
    last_modified: Mapped[datetime]
    vuln_status: Mapped[str]
    evaluator_comment: Mapped[str | None]
    evaluator_solution: Mapped[str | None]
    evaluator_impact: Mapped[str | None]
    cisa_exploit_add: Mapped[date | None]
    cisa_action_due: Mapped[date | None]
    cisa_required_action: Mapped[str | None]
    cisa_vulnerability_name: Mapped[str | None]

    cvss_metrics_v3: Mapped[list["CVSSv3MetricModel"]] = relationship(
        back_populates="cve"
    )
    cvss_metrics_v30: Mapped[list["CVSSv3MetricModel"]] = relationship(
        primaryjoin=lambda: and_(
            CVEModel.id == CVSSv3MetricModel.cve_id,
            CVSSv3MetricModel.version == "3.0",
        ),
        viewonly=True,
    )
    cvss_metrics_v31: Mapped[list["CVSSv3MetricModel"]] = relationship(
        primaryjoin=lambda: and_(
            CVEModel.id == CVSSv3MetricModel.cve_id,
            CVSSv3MetricModel.version == "3.1",
        ),
        viewonly=True,
    )
    cvss_metrics_v2: Mapped[list["CVSSv2MetricModel"]] = relationship(
        back_populates="cve"
    )

    configurations: Mapped[list["ConfigurationModel"]] = relationship(
        back_populates="cve"
    )
    descriptions: Mapped[list["CVEDescriptionModel"]] = relationship(
        back_populates="cve"
    )
    references: Mapped[list["ReferenceModel"]] = relationship(
        back_populates="cve"
    )
    vendor_comments: Mapped[list["VendorCommentModel"]] = relationship(
        back_populates="cve"
    )
    weaknesses: Mapped[list["WeaknessModel"]] = relationship(
        back_populates="cve"
    )


class CVEDescriptionModel(Base):
    __tablename__ = "cve_descriptions"

    cve_id: Mapped[cve_fk] = mapped_column(primary_key=True)
    lang: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[str]

    cve: Mapped[CVEModel] = relationship(back_populates="descriptions")


class ReferenceModel(Base):
    __tablename__ = "cve_references"

    cve_id: Mapped[cve_fk] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(primary_key=True)
    source: Mapped[str | None]
    tags: Mapped[list[str]] = mapped_column(StrListType)

    cve: Mapped[CVEModel] = relationship(back_populates="references")


class WeaknessModel(Base):
    __tablename__ = "cve_weaknesses"

    cve_id: Mapped[cve_fk] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(primary_key=True)

    description: Mapped[list["WeaknessDescriptionModel"]] = relationship(
        back_populates="weakness"
    )
    cve: Mapped[CVEModel] = relationship(back_populates="weaknesses")


class WeaknessDescriptionModel(Base):
    __tablename__ = "cve_weakness_descriptions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["cve_id", "source", "type"],
            [
                "cve_weaknesses.cve_id",
                "cve_weaknesses.source",
                "cve_weaknesses.type",
            ],
            ondelete="CASCADE",
        ),
    )

    cve_id: Mapped[str] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(primary_key=True)

    lang: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(primary_key=True)

    weakness: Mapped[WeaknessModel] = relationship(back_populates="description")


class VendorCommentModel(Base):
    __tablename__ = "cve_vendor_comments"

    cve_id: Mapped[cve_fk] = mapped_column(primary_key=True)
    organization: Mapped[str] = mapped_column(primary_key=True)
    comment: Mapped[str]
    last_modified: Mapped[datetime]

    cve: Mapped[CVEModel] = relationship(back_populates="vendor_comments")


class ConfigurationModel(Base):
    __tablename__ = "cve_configurations"

    id: Mapped[Uuid] = mapped_column(Uuid(as_uuid=False), primary_key=True)
    cve_id: Mapped[cve_fk]
    operator: Mapped[str | None]
    negate: Mapped[bool | None]

    cve: Mapped[CVEModel] = relationship(back_populates="configurations")
    nodes: Mapped[list["NodeModel"]] = relationship(
        back_populates="configuration"
    )


class NodeModel(Base):
    __tablename__ = "cve_nodes"

    id: Mapped[Uuid] = mapped_column(Uuid(as_uuid=False), primary_key=True)
    configuration_id: Mapped[Uuid] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("cve_configurations.id", ondelete="CASCADE"),
        index=True,
    )
    operator: Mapped[str]
    negate: Mapped[bool | None]

    configuration: Mapped[ConfigurationModel] = relationship(
        back_populates="nodes"
    )
    cpe_match: Mapped[list["CPEMatchModel"]] = relationship(
        back_populates="node"
    )


class CPEMatchModel(Base):
    __tablename__ = "cve_cpe_matches"

    match_criteria_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=False), primary_key=True
    )
    node_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("cve_nodes.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    vulnerable: Mapped[bool]
    criteria: Mapped[str]
    version_start_excluding: Mapped[str | None]
    version_start_including: Mapped[str | None]
    version_end_excluding: Mapped[str | None]
    version_end_including: Mapped[str | None]

    node: Mapped[NodeModel] = relationship(back_populates="cpe_match")


class CVSSv2MetricModel(Base):
    __tablename__ = "cve_cvss_metric_v2"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.id", ondelete="CASCADE")
    )
    source: Mapped[str]
    type: Mapped[str]
    base_severity: Mapped[str | None]
    exploitability_score: Mapped[float | None]
    impact_score: Mapped[float | None]
    ac_insuf_info: Mapped[bool | None]
    obtain_all_privilege: Mapped[bool | None]
    obtain_user_privilege: Mapped[bool | None]
    obtain_other_privilege: Mapped[bool | None]
    user_interaction_required: Mapped[bool | None]

    # cvss_data
    vector_string: Mapped[str]
    version: Mapped[str]
    base_score: Mapped[float]
    access_vector: Mapped[str | None]
    access_complexity: Mapped[str | None]
    authentication: Mapped[str | None]
    confidentiality_impact: Mapped[str | None]
    integrity_impact: Mapped[str | None]
    availability_impact: Mapped[str | None]
    exploitability: Mapped[str | None]
    remediation_level: Mapped[str | None]
    report_confidence: Mapped[str | None]
    temporal_score: Mapped[float | None]
    collateral_damage_potential: Mapped[str | None]
    target_distribution: Mapped[str | None]
    confidentiality_requirement: Mapped[str | None]
    integrity_requirement: Mapped[str | None]
    availability_requirement: Mapped[str | None]
    environmental_score: Mapped[float | None]

    cve: Mapped[CVEModel] = relationship(back_populates="cvss_metrics_v2")


class CVSSv3MetricModel(Base):
    __tablename__ = "cve_cvss_metric_v3"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.id", ondelete="CASCADE")
    )
    source: Mapped[str]
    type: Mapped[str]
    exploitability_score: Mapped[float | None]
    impact_score: Mapped[float | None]

    # cvss_data
    vector_string: Mapped[str]
    version: Mapped[str]
    base_score: Mapped[float]
    base_severity: Mapped[str]
    attack_vector: Mapped[str | None]
    attack_complexity: Mapped[str | None]
    privileges_required: Mapped[str | None]
    user_interaction: Mapped[str | None]
    scope: Mapped[str | None]
    confidentiality_impact: Mapped[str | None]
    integrity_impact: Mapped[str | None]
    availability_impact: Mapped[str | None]
    exploit_code_maturity: Mapped[str | None]
    remediation_level: Mapped[str | None]
    report_confidence: Mapped[str | None]
    temporal_score: Mapped[float | None]
    temporal_severity: Mapped[str | None]
    confidentiality_requirement: Mapped[str | None]
    integrity_requirement: Mapped[str | None]
    availability_requirement: Mapped[str | None]
    modified_attack_vector: Mapped[str | None]
    modified_attack_complexity: Mapped[str | None]
    modified_privileges_required: Mapped[str | None]
    modified_user_interaction: Mapped[str | None]
    modified_scope: Mapped[str | None]
    modified_confidentiality_impact: Mapped[str | None]
    modified_integrity_impact: Mapped[str | None]
    modified_availability_impact: Mapped[str | None]
    environmental_score: Mapped[float | None]
    environmental_severity: Mapped[str | None]

    cve: Mapped[CVEModel] = relationship(back_populates="cvss_metrics_v3")
