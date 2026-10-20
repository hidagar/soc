from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0009_weekly_reports")]

    operations = [
        migrations.AddField(model_name="weeklyreport", name="availability_count", field=models.PositiveIntegerField(default=0)),
        migrations.AddField(model_name="weeklyreport", name="other_high_count", field=models.PositiveIntegerField(default=0)),
        migrations.AddField(model_name="weeklyreport", name="findings", field=models.JSONField(default=list)),
        migrations.AddField(model_name="weeklyreport", name="details_limited", field=models.BooleanField(default=False)),
    ]
