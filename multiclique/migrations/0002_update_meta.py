# Generated by Django 4.1.7 on 2023-09-22 13:07

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("multiclique", "0001_initial"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="multicliquepolicy",
            options={"verbose_name": "MultiClique Policy", "verbose_name_plural": "MultiClique Policies"},
        ),
        migrations.AlterModelOptions(
            name="multicliquetransaction",
            options={"verbose_name": "MultiClique Transaction", "verbose_name_plural": "MultiClique Transactions"},
        ),
    ]