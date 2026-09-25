import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("impersonation", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="impersonationscan",
            name="scan_type",
            field=models.CharField(
                choices=[
                    ("IMAGE", "Image"),
                    ("VIDEO", "Video"),
                    ("VOICE", "Voice"),
                ],
                max_length=20,
            ),
        ),
        migrations.CreateModel(
            name="VoiceAnalysis",
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
                ("duration_seconds", models.FloatField(default=0)),
                ("sample_rate", models.PositiveIntegerField(default=16000)),
                ("speech_ratio", models.FloatField(default=0)),
                ("silence_ratio", models.FloatField(default=0)),
                ("pitch_mean_hz", models.FloatField(default=0)),
                ("pitch_std_hz", models.FloatField(default=0)),
                ("pitch_range_hz", models.FloatField(default=0)),
                ("pitch_variation_cv", models.FloatField(default=0)),
                ("spectral_centroid_mean_hz", models.FloatField(default=0)),
                ("spectral_centroid_std_hz", models.FloatField(default=0)),
                ("spectral_bandwidth_std_hz", models.FloatField(default=0)),
                ("spectral_flatness_mean", models.FloatField(default=0)),
                ("spectral_flatness_std", models.FloatField(default=0)),
                ("mfcc_variability", models.FloatField(default=0)),
                ("mfcc_delta_variability", models.FloatField(default=0)),
                ("energy_std_db", models.FloatField(default=0)),
                ("energy_range_db", models.FloatField(default=0)),
                ("zero_crossing_std", models.FloatField(default=0)),
                ("spectral_flux_std", models.FloatField(default=0)),
                ("harmonic_ratio", models.FloatField(default=0)),
                ("clipping_ratio", models.FloatField(default=0)),
                ("voiced_frame_ratio", models.FloatField(default=0)),
                ("synthetic_voice_indicator", models.BooleanField(default=False)),
                ("replay_indicator", models.BooleanField(default=False)),
                ("signal_components", models.JSONField(blank=True, default=dict)),
                ("analysis_details", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "scan",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="voice_analysis",
                        to="impersonation.impersonationscan",
                    ),
                ),
            ],
        ),
    ]
