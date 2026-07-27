# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(AsyncAttrs, DeclarativeBase):
    type_annotation_map = {  # noqa: RUF012
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


class CPEModel(Base):
    __tablename__ = "cpes"

    cpe_name: Mapped[str] = mapped_column(primary_key=True)
    cpe_name_id: Mapped[UUID | None] = mapped_column(unique=True, nullable=True)
    deprecated: Mapped[bool]
    last_modified: Mapped[datetime]
    created: Mapped[datetime]

    cpe_names_model: Mapped["CPENamesModel"] = relationship()
    refs: Mapped[list["ReferenceModel"]] = relationship(
        back_populates="cpe_model"
    )
    titles: Mapped[list["TitleModel"]] = relationship(
        back_populates="cpe_model"
    )
    deprecated_by: Mapped[list["DeprecatedByModel"]] = relationship(
        back_populates="cpe_model"
    )


class CPENamesModel(Base):
    __tablename__ = "cpe_names"

    cpe_name: Mapped[str] = mapped_column(
        ForeignKey("cpes.cpe_name", ondelete="CASCADE"),
        primary_key=True,
    )
    part: Mapped[str]
    vendor: Mapped[str] = mapped_column(index=True)
    product: Mapped[str] = mapped_column(index=True)
    version: Mapped[str]
    version_canonical: Mapped[str | None]
    update: Mapped[str]
    edition: Mapped[str]
    language: Mapped[str]
    sw_edition: Mapped[str]
    target_sw: Mapped[str]
    target_hw: Mapped[str]
    other: Mapped[str]


class TitleModel(Base):
    __tablename__ = "cpe_titles"

    cpe = mapped_column(
        ForeignKey("cpes.cpe_name", ondelete="CASCADE"),
        primary_key=True,
    )
    title: Mapped[str] = mapped_column(primary_key=True)
    lang: Mapped[str] = mapped_column(primary_key=True)

    cpe_model: Mapped[CPEModel] = relationship(back_populates="titles")


class ReferenceModel(Base):
    __tablename__ = "cpe_references"

    cpe: Mapped[str] = mapped_column(
        ForeignKey("cpes.cpe_name", ondelete="CASCADE"),
        primary_key=True,
    )
    ref: Mapped[str] = mapped_column(primary_key=True)
    type: Mapped[str | None]

    cpe_model: Mapped[CPEModel] = relationship(back_populates="refs")


class DeprecatedByModel(Base):
    __tablename__ = "cpe_deprecated_by"

    cpe: Mapped[str] = mapped_column(
        ForeignKey("cpes.cpe_name", ondelete="CASCADE"),
        primary_key=True,
    )

    cpe_name: Mapped[str] = mapped_column(primary_key=True)
    cpe_name_id: Mapped[UUID | None]

    cpe_model: Mapped[CPEModel] = relationship(back_populates="deprecated_by")
