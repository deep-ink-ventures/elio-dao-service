# Generated by Django 4.1.7 on 2023-08-02 10:00

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0003_governance_updates"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="governance",
            name="minimum_majority",
        ),
        migrations.AddField(
            model_name="governance",
            name="min_threshold_configuration",
            field=models.BigIntegerField(default=0),
            preserve_default=False,
        ),
    ]