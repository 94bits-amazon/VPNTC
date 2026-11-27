import os
import logging
from flask import Flask
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from app.models import db, SystemSetting
from app.scheduler import sync_and_expire_vpns

logging.basicConfig(level=logging.INFO)


def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////app/data/vpntc.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if not os.path.exists("/app/data"):
        local_data = os.path.abspath("data")
        os.makedirs(local_data, exist_ok=True)
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(local_data, 'vpntc.db')}"

    db.init_app(app)

    with app.app_context():
        db.create_all()
        interval_minutes = int(SystemSetting.get("EXPIRATION_CHECK_INTERVAL_MINUTES", "15") or "15")

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=sync_and_expire_vpns,
        args=[app],
        trigger="interval",
        minutes=interval_minutes,
        id="vpn_sync_job",
        replace_existing=True,
    )
    scheduler.start()

    from app.routes import bp
    app.register_blueprint(bp)

    return app