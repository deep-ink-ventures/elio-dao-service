import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("multiclique", "0005_rename_signatory_public_key"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="multicliquetransaction",
            name="approvers",
        ),
        migrations.RemoveField(
            model_name="multicliquetransaction",
            name="rejecters",
        ),
        migrations.AddField(
            model_name="multicliquetransaction",
            name="ledger",
            field=models.BigIntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="multicliquetransaction",
            name="nonce",
            field=models.BigIntegerField(default=0),
            preserve_default=False,
        ),
        migrations.CreateModel(
            name="MultiCliqueSignature",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("signature", models.CharField(max_length=256, primary_key=True, serialize=False)),
                (
                    "signatory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.DO_NOTHING, to="multiclique.multicliquesignatory"
                    ),
                ),
            ],
            options={
                "verbose_name": "MultiClique Signature",
                "verbose_name_plural": "MultiClique Signatures",
                "db_table": "multiclique_signature",
            },
        ),
        migrations.AddField(
            model_name="multicliquetransaction",
            name="approvals",
            field=models.ManyToManyField(related_name="transaction_approvals", to="multiclique.multicliquesignature"),
        ),
        migrations.AddField(
            model_name="multicliquetransaction",
            name="rejections",
            field=models.ManyToManyField(related_name="transaction_rejections", to="multiclique.multicliquesignature"),
        ),
    ]
