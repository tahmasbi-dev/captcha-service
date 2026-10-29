import io
import secrets
import string

from captcha.image import ImageCaptcha

from captcha_service.application.ports.captcha_generator import CaptchaGenerator


class LeptureImageCaptchaGenerator(CaptchaGenerator):
    def __init__(
        self,
        *,
        width: int = 280,
        height: int = 90,
        fonts: list[str] | None = None,
        length: int = 6,
    ) -> None:
        # fonts load here, once. Build this adapter at the composition
        # root, not per request.
        self._image = ImageCaptcha(width=width, height=height, fonts=fonts)
        self._length = length
        self._alphabet = string.ascii_uppercase + string.digits
        self.last_solution: str | None = None   # test hook, don't use in prod configs

    def generate(self) -> str:
        # secrets, not random; these caps protect real things.
        solution = "".join(
            secrets.choice(self._alphabet) for _ in range(self._length)
        )
        self.last_solution = solution
        return solution

    def render(self, solution: str) -> bytes:
        data: io.BytesIO = self._image.generate(solution, format="png")
        return data.getvalue()          # plain bytes, not the BytesIO buffer