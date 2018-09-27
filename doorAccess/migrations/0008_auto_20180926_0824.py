# Generated by Django 2.0.5 on 2018-09-26 08:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('doorAccess', '0007_auto_20180926_0819'),
    ]

    operations = [
        migrations.AlterField(
            model_name='nfcdacphase1',
            name='userKeys',
            field=models.CharField(max_length=20),
        ),
        migrations.AlterField(
            model_name='nfcdacphase2',
            name='userKeys',
            field=models.CharField(max_length=20),
        ),
        migrations.AlterField(
            model_name='nfcdacphase3',
            name='userKeys',
            field=models.CharField(max_length=20),
        ),
        migrations.AlterField(
            model_name='nfcdoor',
            name='doorUUID',
            field=models.CharField(default='OKTlBAg5ltLFyJL2', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='AESEncryptKey',
            field=models.CharField(default='dPh5pIIOvN0rsNPc', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='accesTrue',
            field=models.CharField(default='KenVNEN3uTXW6Yk3ovVwUYJTaH8zv9cI', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='keyUTID',
            field=models.CharField(default='GLTudltDPzy4a5xrMkOlygOhD4GFNsrG', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='keyUUID',
            field=models.CharField(default='MEufEhKwIr77R2c7bNNk', max_length=20),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='TDAT',
            field=models.CharField(default='ubTHpOpfy3CNQeRf', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='accesingUDID',
            field=models.CharField(default='l6Zu1cPLY1gE62r9', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='accessingUUID',
            field=models.CharField(default='ivNgJd7', max_length=7),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='encryptionKey',
            field=models.CharField(default='gjCUEpgA5C6rSweg', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='encryptionSalt',
            field=models.CharField(default='YnDWlsAOIRoM50at', max_length=16),
        ),
    ]