from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("threat_detection", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="threat",
            name="source_type",
            field=models.CharField(
                choices=[
                    ("URL", "URL"),
                    ("EMAIL", "Email"),
                    ("MESSAGE", "Message"),
                    ("IMAGE", "Image"),
                    ("VIDEO", "Video"),
                    ("VOICE", "Voice"),
                    ("LOGIN", "Login Activity"),
                    ("DEVICE", "Device Activity"),
                    ("NETWORK", "Network Activity"),
                    ("FILE", "File"),
                    ("OTHER", "Other"),
                ],
                max_length=30,
            ),
        ),
    ]
