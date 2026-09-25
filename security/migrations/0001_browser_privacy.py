from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="BrowserPrivacyPairing",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("code_hash", models.CharField(max_length=64, unique=True)),
                ("expires_at", models.DateTimeField()),
                ("used_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="browser_privacy_pairings",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(
                        fields=["user", "expires_at"],
                        name="security_br_user_id_2a2a8e_idx",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="BrowserPrivacyScan",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("browser", models.CharField(blank=True, max_length=100)),
                ("browser_version", models.CharField(blank=True, max_length=100)),
                ("platform", models.CharField(blank=True, max_length=150)),
                ("cookie_count", models.PositiveIntegerField(default=0)),
                ("sensitive_cookie_count", models.PositiveIntegerField(default=0)),
                ("extension_count", models.PositiveIntegerField(default=0)),
                ("high_impact_extension_count", models.PositiveIntegerField(default=0)),
                (
                    "cookie_metadata",
                    models.TextField(
                        blank=True,
                        default=list,
                    ),
                ),
                (
                    "extension_metadata",
                    models.TextField(
                        blank=True,
                        default=list,
                    ),
                ),
                (
                    "summary",
                    models.TextField(
                        blank=True,
                        default=dict,
                    ),
                ),
                ("scanned_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="browser_privacy_scans",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-scanned_at"],
                "indexes": [
                    models.Index(
                        fields=["user", "-scanned_at"],
                        name="security_br_user_id_9c3e8b_idx",
                    ),
                ],
            },
        ),
    ]
