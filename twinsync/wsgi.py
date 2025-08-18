import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'twinsync.settings')

application = get_wsgi_application()

# 👇 This makes Vercel happy
app = application