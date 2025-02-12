# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later


from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Uuid,
)
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class BaseDatabaseModel(AsyncAttrs, DeclarativeBase):
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


class CPEMatchStringDatabaseModel(BaseDatabaseModel):
    __tablename__ = "cpe_match_strings"

    match_criteria_id: Mapped[Uuid] = mapped_column(
        Uuid(as_uuid=False), primary_key=True
    )
    criteria: Mapped[str]
    status: Mapped[str]
    cpe_last_modified: Mapped[datetime | None]
    created: Mapped[datetime]
    last_modified: Mapped[datetime]
    version_start_including: Mapped[str | None]
    version_start_excluding: Mapped[str | None]
    version_end_including: Mapped[str | None]
    version_end_excluding: Mapped[str | None]
    matches: Mapped[list["CPEMatchDatabaseModel"] | None] = relationship(
        back_populates="cpe_match_string_model"
    )


class CPEMatchDatabaseModel(BaseDatabaseModel):
    __tablename__ = "cpe_match"

    match_criteria_id: Mapped[Uuid] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("cpe_match_strings.match_criteria_id", ondelete="CASCADE"),
        primary_key=True,
    )
    cpe_name: Mapped[str]
    cpe_name_id: Mapped[Uuid] = mapped_column(
        Uuid(as_uuid=False), primary_key=True
    )

    cpe_match_string_model: Mapped[CPEMatchStringDatabaseModel] = relationship(
        back_populates="matches"
    )
