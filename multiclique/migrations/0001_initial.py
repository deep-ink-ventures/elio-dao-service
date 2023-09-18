# Generated by Django 4.1.7 on 2023-09-18 16:24

import django.contrib.postgres.fields
import django.db.models.deletion
from django.db import migrations, models

import multiclique.models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="MultiCliqueAccount",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("address", models.CharField(max_length=128, primary_key=True, serialize=False)),
                (
                    "public_keys",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.CharField(max_length=256), default=list, size=None
                    ),
                ),
                ("default_threshold", models.PositiveIntegerField(null=True)),
            ],
            options={
                "verbose_name": "MultiClique Account",
                "verbose_name_plural": " MultiClique Accounts",
                "db_table": "multiclique_accounts",
            },
        ),
        migrations.CreateModel(
            name="MultiCliquePolicy",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=256, primary_key=True, serialize=False)),
                ("active", models.BooleanField(default=False)),
            ],
            options={
                "verbose_name": "MultiCliqueAccount Policy",
                "verbose_name_plural": "MultiCliqueAccount Policies",
                "db_table": "multiclique_policies",
            },
        ),
        migrations.CreateModel(
            name="MultiCliqueTransaction",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("xdr", models.CharField(max_length=1024)),
                ("preimage_hash", models.CharField(max_length=1024)),
                ("call_func", models.CharField(max_length=256, null=True)),
                ("call_args", models.JSONField(null=True)),
                (
                    "signers",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.CharField(max_length=256), default=list, size=None
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("PENDING", "pending"),
                            ("APPROVED", "approved"),
                            ("REJECTED", "rejected"),
                            ("EXECUTED", "executed"),
                        ],
                        default=multiclique.models.TransactionStatus["PENDING"],
                        max_length=16,
                    ),
                ),
                ("executed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "multiclique_account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="transactions",
                        to="multiclique.multicliqueaccount",
                    ),
                ),
            ],
            options={
                "verbose_name": "MultiCliqueAccount Transaction",
                "verbose_name_plural": "MultiCliqueAccount Transactions",
                "db_table": "multiclique_transactions",
            },
        ),
        migrations.AddField(
            model_name="multicliqueaccount",
            name="policy",
            field=models.ForeignKey(
                null=True, on_delete=django.db.models.deletion.SET_NULL, to="multiclique.multicliquepolicy"
            ),
        ),
    ]