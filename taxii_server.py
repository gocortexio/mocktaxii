import json
from datetime import datetime, timezone
from flask import request, jsonify, abort
from functools import wraps
from models import ApiKey, RequestLog, ServerStats, db
from stix_generator import STIXGenerator

class TAXIIServer:
    """TAXII 2.x server implementation"""
    
    API_ROOT = "api"
    COLLECTION_ID = "threat-intel-demo"
    
    @staticmethod
    def validate_api_key(f):
        """Decorator to validate API key for TAXII endpoints"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for API key in headers
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                abort(401, description="Missing Authorization header")
            
            # Handle both Bearer token and direct API key formats
            if auth_header.startswith('Bearer '):
                api_key_value = auth_header.replace('Bearer ', '')
            else:
                # Direct API key format (XSIAM with _header:Authorization)
                api_key_value = auth_header
            api_key = ApiKey.query.filter_by(key=api_key_value, is_active=True).first()
            
            if not api_key:
                abort(401, description="Invalid API key")
            
            # Get real client IP considering proxy headers
            from app import get_real_ip
            
            # Log the request
            log_entry = RequestLog()
            log_entry.api_key_id = api_key.id
            log_entry.endpoint = request.endpoint
            log_entry.method = request.method
            log_entry.ip_address = get_real_ip()
            log_entry.user_agent = request.headers.get('User-Agent')
            db.session.add(log_entry)
            
            # Increment API key usage
            api_key.request_count += 1
            db.session.commit()
            
            # Add api_key to kwargs for use in the endpoint
            kwargs['api_key'] = api_key
            kwargs['log_entry'] = log_entry
            
            return f(*args, **kwargs)
        return decorated_function
    
    @staticmethod
    def get_discovery_response():
        """TAXII Discovery endpoint response"""
        return {
            "title": "MockTAXII v0.2.1",
            "description": "A lightweight TAXII 2.x server for XSIAM demonstrations",
            "contact": "demo@mocktaxii.local",
            "default": f"/taxii2/{TAXIIServer.API_ROOT}/",
            "api_roots": [
                f"/taxii2/{TAXIIServer.API_ROOT}/"
            ]
        }
    
    @staticmethod
    def get_api_root_response():
        """TAXII API Root endpoint response"""
        return {
            "title": "MockTAXII v0.2.1 API Root",
            "description": "Demo threat intelligence data for XSIAM testing",
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 10485760  # 10MB
        }
    
    @staticmethod
    def get_collections_response():
        """TAXII Collections endpoint response"""
        return {
            "collections": [
                {
                    "id": TAXIIServer.COLLECTION_ID,
                    "title": "Demo Threat Intelligence Collection",
                    "description": "Mock STIX threat intelligence indicators for demonstration purposes",
                    "can_read": True,
                    "can_write": False,
                    "media_types": [
                        "application/stix+json;version=2.1"
                    ]
                }
            ]
        }
    
    @staticmethod
    def get_collection_objects(collection_id, limit=50, added_after=None):
        """Get objects from a specific collection"""
        if collection_id != TAXIIServer.COLLECTION_ID:
            abort(404, description="Collection not found")
        
        # Generate fresh mock data for each request
        try:
            limit = min(int(limit), 100)  # Cap at 100 objects
        except (ValueError, TypeError):
            limit = 50
        
        # Generate related STIX objects with relationships
        stix_objects = STIXGenerator.generate_related_indicators_bundle(limit)
        
        # Create STIX bundle
        bundle = STIXGenerator.create_stix_bundle(stix_objects)
        
        # Update server stats
        stats = ServerStats.get_stats()
        stats.increment_indicators(len(stix_objects))
        
        return bundle
    
    @staticmethod
    def get_collection_manifest(collection_id, limit=50, added_after=None):
        """Get manifest for a specific collection"""
        if collection_id != TAXIIServer.COLLECTION_ID:
            abort(404, description="Collection not found")
        
        try:
            limit = min(int(limit), 100)
        except (ValueError, TypeError):
            limit = 50
        
        # Generate manifest entries
        objects = []
        for _ in range(limit):
            objects.append({
                "id": f"indicator--{STIXGenerator.generate_timestamp()}",
                "date_added": STIXGenerator.generate_timestamp(),
                "version": STIXGenerator.generate_timestamp(),
                "media_type": "application/stix+json;version=2.1"
            })
        
        return {
            "objects": objects
        }
    
    @staticmethod
    def get_collection_info(collection_id):
        """Get information about a specific collection"""
        if collection_id != TAXIIServer.COLLECTION_ID:
            abort(404, description="Collection not found")
        
        return {
            "id": TAXIIServer.COLLECTION_ID,
            "title": "Demo Threat Intelligence Collection",
            "description": "Mock STIX threat intelligence indicators for demonstration purposes",
            "can_read": True,
            "can_write": False,
            "media_types": [
                "application/stix+json;version=2.1"
            ]
        }
