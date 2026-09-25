from django.db import migrations
import security.fields


class Migration(migrations.Migration):
    dependencies = [("impersonation", "0002_voice_analysis")]

    operations = [
        migrations.AlterField(model_name="impersonationscan", name="explanation", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="deepfakeanalysis", name="analysis_details", field=security.fields.EncryptedJSONField(blank=True, default=dict)),
        migrations.AlterField(model_name="identityanalysis", name="impersonation_indicators", field=security.fields.EncryptedJSONField(blank=True, default=list)),
        migrations.AlterField(model_name="identityanalysis", name="analysis_details", field=security.fields.EncryptedJSONField(blank=True, default=dict)),
        migrations.AlterField(model_name="impersonationevidence", name="evidence_value", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="voiceanalysis", name="signal_components", field=security.fields.EncryptedJSONField(blank=True, default=dict)),
        migrations.AlterField(model_name="voiceanalysis", name="analysis_details", field=security.fields.EncryptedJSONField(blank=True, default=dict)),
    ]
