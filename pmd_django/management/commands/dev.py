import os
import subprocess
from concurrent import futures

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Build the react frontend into static and then start the dev server"

    def handle(self, *args, **options):
        os.chdir("./frontend")

        def build():
            completed = None
            try:
                completed = subprocess.run("npm run build", shell=True)
            except KeyboardInterrupt:
                pass
            if completed and completed.returncode != 0:
                raise CommandError("Unable to build frontend")

        def dev():
            completed = None
            try:
                completed = subprocess.run("npm run dev", shell=True)
            except KeyboardInterrupt:
                pass
            if completed and completed.returncode != 0:
                raise CommandError(f"Unable to run npm run dev: {completed.stdout}")

        def serve():
            completed = None
            try:
                completed = subprocess.run("python ../manage.py runserver", shell=True)
            except KeyboardInterrupt:
                pass
            if completed and completed.returncode != 0:
                raise CommandError("Unable to build frontend")

        try:
            server_command = None
            with open("package.json") as f:
                if "\"main\"" in f.read():
                    server_command = build
                else:
                    server_command = dev

            with futures.ThreadPoolExecutor(max_workers=2) as executor:
                executor.submit(server_command)
                executor.submit(serve)
        except KeyboardInterrupt:
            pass
