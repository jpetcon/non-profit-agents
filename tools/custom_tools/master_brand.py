import json
from pathlib import Path

def _brand() -> dict:
    try:
        import os
        strategy_path = Path(os.getenv('MASTERBRAND_PATH', str(Path(__file__).resolve().parent / 'lib' / 'strategy.json')))
        with strategy_path.open(encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def get_strategy() -> str:
    """Retrieve the charity's written strategy."""
    return _brand().get('strategy') or 'The charity strategy has not been configured.'


def get_brand_profile() -> dict:
    """Retrieve the charity's organisation name, mission and values."""
    brand = _brand()
    return {key: brand.get(key) or 'Not configured' for key in ('organisation_name', 'mission', 'values')}


def get_target_audience() -> str:
    """Retrieve the charity's intended audience."""
    return _brand().get('target_audience') or 'The target audience has not been configured.'


def get_brand_voice() -> str:
    """Retrieve the charity's voice and communication guidelines."""
    return _brand().get('brand_voice') or 'The brand voice has not been configured.'
