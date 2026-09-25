from django.db import migrations
import security.fields

class Migration(migrations.Migration):
    dependencies = [("audit_logs", "0002_auditlog_resource_auditlog_resource_id_and_more")]
    operations = [
        migrations.AlterField(model_name="auditlog", name="user_agent", field=security.fields.EncryptedTextField(blank=True)),
        migrations.AlterField(model_name="auditlog", name="description", field=security.fields.EncryptedTextField(blank=True)),
    ]
