"""MockTAXII Version Information"""

__version__ = "0.4.1"
__title__ = "MockTAXII"
__description__ = "Comprehensive TAXII 2.x server with enhanced threat intelligence capabilities"
__author__ = "MockTAXII Team"
__license__ = "MIT"

def get_version_info():
    """Get formatted version information"""
    return {
        "version": __version__,
        "title": __title__,
        "description": __description__,
        "author": __author__,
        "license": __license__
    }

def get_version_string():
    """Get version string for display"""
    return f"{__title__} v{__version__}"