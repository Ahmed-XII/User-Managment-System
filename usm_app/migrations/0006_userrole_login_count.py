# Generated by Django 5.1.4 on 2024-12-11 09:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usm_app', '0005_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='userrole',
            name='login_count',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
