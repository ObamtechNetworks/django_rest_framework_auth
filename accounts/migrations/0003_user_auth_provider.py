# Generated by Django 5.0.6 on 2024-05-08 21:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_user_groups_user_user_permissions_onetimepassword'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='auth_provider',
            field=models.CharField(default='email', max_length=50),
        ),
    ]
