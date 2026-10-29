from datetime import datetime
from abc import ABC, abstractmethod

class Clock(ABC):
    """Timezone-aware UTC timestamps. Injected so tests can pin the time."""
    
    @abstractmethod
    def now(self) -> datetime:...
        
        