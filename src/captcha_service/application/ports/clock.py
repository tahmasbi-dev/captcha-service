from datetime import datetime
from abc import ABC, abstractmethod

class Clock(ABC):
    """Timezone-aware UTC timestamp. Injected so tests are deterministic."""
    
    @abstractmethod
    def now(self) -> datetime:...
        
        