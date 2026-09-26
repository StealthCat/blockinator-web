"""Release metadata shared by the application, image and updater."""
import os

APP_VERSION = "1.20.0"
BUILD_SHA = os.getenv("BLOCKINATOR_BUILD_SHA", "development")
BUILD_CHANNEL = os.getenv("BLOCKINATOR_BUILD_CHANNEL", "development")
SCHEMA_VERSION = 1
UPDATER_PROTOCOL = 1
