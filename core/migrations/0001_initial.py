# Generated by Django 4.1.7 on 2023-05-10 10:43

import django.db.models.deletion
from django.db import migrations, models

import core.models
import core.utils


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Account",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "address",
                    models.CharField(editable=False, max_length=128, primary_key=True, serialize=False, unique=True),
                ),
            ],
            options={
                "verbose_name": "Account",
                "verbose_name_plural": "Accounts",
            },
        ),
        migrations.CreateModel(
            name="Block",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "hash",
                    models.CharField(editable=False, max_length=128, primary_key=True, serialize=False, unique=True),
                ),
                ("number", models.BigIntegerField(editable=False, unique=True)),
                ("parent_hash", models.CharField(editable=False, max_length=128, null=True, unique=True)),
                ("extrinsic_data", models.JSONField(default=dict)),
                ("event_data", models.JSONField(default=dict)),
                ("executed", models.BooleanField(db_index=True, default=False)),
            ],
            options={
                "verbose_name": "Block",
                "verbose_name_plural": "Blocks",
            },
        ),
        migrations.CreateModel(
            name="Dao",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.CharField(max_length=128, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=128, null=True)),
                ("metadata", models.JSONField(null=True)),
                ("metadata_url", models.CharField(max_length=256, null=True)),
                ("metadata_hash", models.CharField(max_length=256, null=True)),
                ("setup_complete", models.BooleanField(default=False)),
                (
                    "creator",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_daos",
                        to="core.account",
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="owned_daos", to="core.account"
                    ),
                ),
            ],
            options={
                "verbose_name": "DAO",
                "verbose_name_plural": "DAOs",
            },
        ),
        migrations.CreateModel(
            name="Proposal",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.CharField(max_length=128, primary_key=True, serialize=False)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("RUNNING", "running"),
                            ("PENDING", "pending"),
                            ("REJECTED", "rejected"),
                            ("IMPLEMENTED", "implemented"),
                            ("FAULTED", "faulted"),
                        ],
                        default=core.models.ProposalStatus["RUNNING"],
                        max_length=16,
                    ),
                ),
                ("fault", models.TextField(null=True)),
                ("birth_block_number", models.PositiveBigIntegerField()),
                ("metadata", models.JSONField(null=True)),
                ("metadata_url", models.CharField(max_length=256, null=True)),
                ("metadata_hash", models.CharField(max_length=256, null=True)),
                (
                    "creator",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="proposals",
                        to="core.account",
                    ),
                ),
                (
                    "dao",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="proposals", to="core.dao"
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="Vote",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("in_favor", models.BooleanField(db_index=True, null=True)),
                ("voting_power", core.utils.BiggerIntField(max_length=1024)),
                (
                    "proposal",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="votes", to="core.proposal"
                    ),
                ),
                (
                    "voter",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="votes", to="core.account"
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="ProposalReport",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("reason", models.TextField()),
                ("proposal", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="core.proposal")),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="Governance",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("type", models.CharField(choices=[("MAJORITY_VOTE", "majority vote")], max_length=128)),
                ("proposal_duration", models.IntegerField()),
                ("proposal_token_deposit", core.utils.BiggerIntField(max_length=1024)),
                ("minimum_majority", models.IntegerField()),
                (
                    "dao",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE, related_name="governance", to="core.dao"
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="Asset",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("id", models.PositiveBigIntegerField(primary_key=True, serialize=False)),
                ("total_supply", core.utils.BiggerIntField(max_length=1024)),
                (
                    "dao",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE, related_name="asset", to="core.dao"
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="assets", to="core.account"
                    ),
                ),
            ],
            options={
                "verbose_name": "Asset",
                "verbose_name_plural": "Assets",
            },
        ),
        migrations.CreateModel(
            name="AssetHolding",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("balance", core.utils.BiggerIntField(max_length=1024)),
                (
                    "asset",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="holdings", to="core.asset"
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="holdings", to="core.account"
                    ),
                ),
            ],
            options={
                "verbose_name": "Asset Holding",
                "verbose_name_plural": "Asset Holdings",
                "db_table": "core_asset_holding",
                "unique_together": {("asset", "owner")},
            },
        ),
    ]
