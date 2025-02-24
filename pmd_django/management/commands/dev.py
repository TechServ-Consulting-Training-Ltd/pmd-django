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

        def serve():
            completed = None
            try:
                completed = subprocess.run("python ../manage.py runserver", shell=True)
            except KeyboardInterrupt:
                pass
            if completed and completed.returncode != 0:
                raise CommandError("Unable to build frontend")

        try:
            with futures.ThreadPoolExecutor(max_workers=2) as executor:
                executor.submit(build)
                executor.submit(serve)
        except KeyboardInterrupt:
            pass
