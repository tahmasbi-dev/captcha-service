import io
import secrets
import string

from captcha.image import ImageCaptcha

from captcha_service.application.ports.captcha_generator import CaptchaGenerator


_ALPHABET = string.ascii_uppercase + string.digits


class ImageCaptchaGenerator(CaptchaGenerator):
    def __init__(
        self,
        *,
        width: int = 280,
        height: int = 90,
        fonts: list[str] | None = None,
        length: int = 6,
    ) -> None:
        # Fonts load here, once. Construct at the composition root.
        self._image = ImageCaptcha(width=width, height=height, fonts=fonts)
        self._length = length

    def generate(self) -> str:
        return "".join(secrets.choice(_ALPHABET) for _ in range(self._length))

    def render(self, solution: str) -> bytes:
        buf: io.BytesIO = self._image.generate(solution, format="png")
        return buf.getvalue()          # .getvalue() — never return the BytesIO