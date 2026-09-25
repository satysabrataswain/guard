from django.db import migrations, models
import security.fields


class Migration(migrations.Migration):
    dependencies = [("threat_detection", "0002_voice_source")]

    operations = [
        migrations.AlterField(model_name="threat", name="input_data", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="threat", name="explanation", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="threatevidence", name="evidence_value", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="threatanalysis", name="analysis_result", field=security.fields.EncryptedJSONField(blank=True, default=dict)),
    ]
