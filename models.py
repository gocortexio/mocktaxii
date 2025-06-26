from app import db
from datetime import datetime, timezone
import uuid

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    request_count = db.Column(db.Integer, nullable=False, default=0)
    
    def __repr__(self):
        return f'<ApiKey {self.name}>'

class RequestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_key.id'), nullable=True)
    endpoint = db.Column(db.String(200), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    indicators_served = db.Column(db.Integer, default=0)
    
    api_key = db.relationship('ApiKey', backref=db.backref('requests', lazy=True))
    
    def __repr__(self):
        return f'<RequestLog {self.endpoint}>'

class ServerStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_indicators_served = db.Column(db.Integer, nullable=False, default=0)
    total_requests = db.Column(db.Integer, nullable=False, default=0)
    last_updated = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def get_stats(cls):
        stats = cls.query.first()
        if not stats:
            stats = cls()
            db.session.add(stats)
            db.session.commit()
        return stats
    
    def increment_indicators(self, count):
        self.total_indicators_served += count
        self.total_requests += 1
        self.last_updated = datetime.now(timezone.utc)
        db.session.commit()

class ThreatActor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    threat_actor_types = db.Column(db.JSON, default=lambda: ["criminal-enterprise"])
    sophistication = db.Column(db.String(50), default="intermediate")
    resource_level = db.Column(db.String(50), default="organization")
    primary_motivation = db.Column(db.String(50), default="financial-gain")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<ThreatActor {self.name}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active threat actor"""
        actors = cls.query.filter_by(is_active=True).all()
        if actors:
            import random
            return random.choice(actors)
        return None
    
    @classmethod
    def seed_default_actors(cls):
        """Seed the database with default threat actors if none exist"""
        if cls.query.count() == 0:
            default_actors = [
                "Academic Serpens", "Agent Serpens", "Agonizing Serpens", "Alloy Taurus",
                "Ambitious Scorpius", "Bashful Scorpius", "Bitter Scorpius", "Blustering Scorpius",
                "Boggy Serpens", "Charging Taurus", "Chubby Scorpius", "Cloaked Ursa",
                "Dapper Scorpius", "Dark Scorpius", "Devious Serpens", "Dicing Taurus",
                "Digging Taurus", "Evasive Serpens", "Fiddling Scorpius", "Fighting Ursa",
                "Howling Scorpius", "Ignoble Scorpius", "Insidious Taurus", "Invisible Scorpius",
                "Jumper Taurus", "Jumpy Pisces", "Mocking Draco", "Muddled Libra",
                "Mushy Scorpius", "Mythic Ursa", "Opaque Draco", "Pensive Ursa",
                "Pilfering Scorpius", "Playful Taurus", "Powerful Scorpius", "Procedural Scorpius",
                "Protesting Scorpius", "Razing Ursa", "Salty Scorpius", "Sentinel Taurus",
                "Shifty Scorpius", "Slow Pisces", "Spicy Scorpius", "Spikey Scorpius",
                "Spoiled Scorpius", "Squalid Scorpius", "Squeaking Scorpius", "Stale Scorpius",
                "Stately Taurus", "Stumped Scorpius", "Transforming Scorpius", "Trident Ursa",
                "Twinkling Scorpius", "Weary Scorpius", "White Lynx"
            ]
            
            for actor_name in default_actors:
                actor = cls(
                    name=actor_name,
                    description=f"{actor_name} is a threat actor group known for targeted attacks"
                )
                db.session.add(actor)
            
            db.session.commit()
