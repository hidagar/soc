from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0010_report_findings")]

    operations = [
        migrations.AddField(model_name="weeklyreport", name="provider_message_id", field=models.CharField(blank=True, max_length=180)),
        migrations.CreateModel(
            name="MailSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("region", models.CharField(choices=[("global", "SendGrid global"), ("eu", "SendGrid EU regional")], default="global", max_length=10, verbose_name="Región de la cuenta")),
                ("encrypted_api_key", models.TextField(blank=True)),
                ("from_email", models.EmailField(max_length=254, verbose_name="Correo remitente")),
                ("enabled", models.BooleanField(default=False)),
                ("last_tested_at", models.DateTimeField(blank=True, null=True)),
                ("last_test_ok", models.BooleanField(default=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"verbose_name": "Correo de informes"},
        ),
    ]
