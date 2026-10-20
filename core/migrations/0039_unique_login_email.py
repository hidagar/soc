from django.conf import settings
from django.db import migrations


def add_unique_email(apps,schema_editor):
    user=apps.get_model(settings.AUTH_USER_MODEL)
    table=schema_editor.quote_name(user._meta.db_table)
    schema_editor.execute(f"CREATE UNIQUE INDEX soc_user_login_email_unique ON {table} (LOWER(TRIM(email))) WHERE TRIM(email) <> ''")


def remove_unique_email(apps,schema_editor):
    schema_editor.execute('DROP INDEX soc_user_login_email_unique')


class Migration(migrations.Migration):
    dependencies=[('core','0038_grandstream_gcc'),migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations=[migrations.RunPython(add_unique_email,remove_unique_email)]
