from django.db import migrations
import security.fields


class Migration(migrations.Migration):
    dependencies = [("phishing", "0001_initial")]

    operations = [
        migrations.AlterField(model_name="phishingscan", name="input_data", field=security.fields.EncryptedTextField()),
        migrations.AlterField(model_name="phishingscan", name="explanation", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="urlanalysis", name="analysis_details", field=security.fields.EncryptedJSONField(blank=True, default=dict)),
        migrations.AlterField(model_name="emailanalysis", name="analysis_details", field=security.fields.EncryptedJSONField(blank=True, default=dict)),
    ]
