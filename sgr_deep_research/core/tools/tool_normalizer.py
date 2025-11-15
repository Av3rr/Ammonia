from pydantic import BaseModel, field_validator

class ToolNormalizerMixin(BaseModel):
    """
    Mixin для нормализации имен инструментов из PascalCase в snake_case.
    """

    @field_validator("tool_name_discriminator", mode="before", check_fields=False)
    @classmethod
    def _normalize_tool_name(cls, v):
        """Конвертирует 'MyToolName' в 'my_tool_name'."""
        if isinstance(v, str):
            s1 = v[0].lower()
            for char in v[1:]:
                if char.isupper():
                    s1 += '_'
                s1 += char.lower()

            normalized = v.lower()
            return normalized
        return v
