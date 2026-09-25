from django.db import migrations
import security.fields


class Migration(migrations.Migration):
    dependencies = [("incidents", "0001_initial")]

    operations = [
        migrations.AlterField(model_name="incident", name="description", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="incidentevidence", name="evidence_value", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="responseaction", name="description", field=security.fields.EncryptedTextField(blank=True)),
    ]
