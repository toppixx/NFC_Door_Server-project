# Generated by Django 2.0.5 on 2018-07-15 06:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('profiles_api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='nfcdoor',
            name='doorUUID',
            field=models.CharField(default='cZigauucnopk9hbY', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='AESEncryptKey',
            field=models.CharField(default='yhXZKGQoaSWcYAPZ', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='accesTrue',
            field=models.CharField(default='enUm1tIuxCEdBoxe20wVt8DUoWuNEkJv', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='keyUTID',
            field=models.CharField(default='VtDuWtgkSRscUCcSVmnl3nk1zXqMVSpc', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='keyUUID',
            field=models.CharField(default='VO2pBMt', max_length=7),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='TDAT',
            field=models.CharField(default='EXXGPQ6xvujFj1cb', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='accesingUDID',
            field=models.CharField(default='6YemzrMa00Pp6AZl', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='accessingUUID',
            field=models.CharField(default='IiHKtBO', max_length=7),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='encryptionKey',
            field=models.CharField(default='C5OdHOf9raU35z1f', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='encryptionSalt',
            field=models.CharField(default='oJHGn5l8yPiWHX8X', max_length=16),
        ),
    ]