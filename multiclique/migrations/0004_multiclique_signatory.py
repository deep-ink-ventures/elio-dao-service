# Generated by Django 4.1.7 on 2023-09-27 14:29

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("multiclique", "0003_multiclique_account_changes"),
    ]

    operations = [
        migrations.CreateModel(
            name="MultiCliqueSignatory",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("public_key", models.CharField(max_length=128, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=128, null=True)),
            ],
            options={
                "verbose_name": "MultiClique Signatory",
                "verbose_name_plural": "MultiClique Signatories",
                "db_table": "multiclique_signatory",
            },
        ),
        migrations.RemoveField(
            model_name="multicliqueaccount",
            name="signatories",
        ),
        migrations.AddField(
            model_name="multicliqueaccount",
            name="signatories",
            field=models.ManyToManyField(related_name="accounts", to="multiclique.multicliquesignatory"),
        ),
    ]
