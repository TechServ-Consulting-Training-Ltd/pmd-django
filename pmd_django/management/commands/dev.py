import os
import subprocess
from concurrent import futures

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Build the react frontend into static and then start the dev server"

    def handle(self, *args, **options):
        os.chdir("./frontend")

        def frontend():
            completed = None
            try:
                completed = subprocess.run("npm run dev", shell=True)
            except KeyboardInterrupt:
                pass
            if completed and completed.returncode != 0:
                raise CommandError("Unable to start dev server")

        def backend():
            completed = None
            try:
                completed = subprocess.run("python ../manage.py runserver", shell=True)
            except KeyboardInterrupt:
                pass
            if completed and completed.returncode != 0:
                raise CommandError("Unable to start the backend")

        try:
            with futures.ThreadPoolExecutor(max_workers=2) as executor:
                executor.submit(frontend)
                executor.submit(backend)
        except KeyboardInterrupt:
            pass
