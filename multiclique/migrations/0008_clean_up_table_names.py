# Generated by Django 4.1.7 on 2023-10-12 14:48

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("multiclique", "0007_update_policy_and_transaction"),
    ]

    operations = [
        migrations.AlterModelTable(
            name="multicliqueaccount",
            table="multiclique_account",
        ),
        migrations.AlterModelTable(
            name="multicliquepolicy",
            table="multiclique_policy",
        ),
        migrations.AlterModelTable(
            name="multicliquetransaction",
            table="multiclique_transaction",
        ),
    ]
