from abc import ABC, abstractmethod

class CaptchaGenerator(ABC):
    @abstractmethod
    def generate(self) -> str: ...
    @abstractmethod
    def render(self, solution: str) -> bytes: ...