from django.db import migrations, models

import myapp.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='BotSubmission',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email_submitted', models.CharField(blank=True, max_length=254, null=True)),
                ('raw_body', models.TextField()),
                ('ip_address', models.CharField(max_length=64)),
                ('forwarded_for', models.CharField(blank=True, max_length=256, null=True)),
                ('user_agent', models.TextField(blank=True, null=True)),
                ('referer', models.TextField(blank=True, null=True)),
                ('headers_json', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('geo', models.JSONField(blank=True, null=True)),
                ('detection_tags', myapp.fields.FlexibleArrayField(blank=True, default=list)),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [
                    models.Index(fields=['-created_at'], name='myapp_botsub_created_idx'),
                    models.Index(fields=['ip_address'], name='myapp_botsub_ip_idx'),
                    models.Index(fields=['email_submitted'], name='myapp_botsub_email_idx'),
                ],
            },
        ),
    ]
