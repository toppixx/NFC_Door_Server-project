# Generated by Django 2.0.5 on 2018-07-14 20:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('profiles_api', '0021_auto_20180714_2032'),
    ]

    operations = [
        migrations.AlterField(
            model_name='nfckey',
            name='AESEncryptKey',
            field=models.TextField(default='2HuGptapDj0sDOcBDXeFYCkS5EptUgTE', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='accesTrue',
            field=models.TextField(default='oFGLhwucxSw38VXsguBAh5fAqYx4i50p', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='TDAT',
            field=models.TextField(default='L5xpAblV2B1CBsLP', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='encryptionKey',
            field=models.TextField(default='JStIGfDZR4hdCy63', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='encryptionSalt',
            field=models.TextField(default='fIvnn93ZO324kPtj', max_length=16),
        ),
    ]
