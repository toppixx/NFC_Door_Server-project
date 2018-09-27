# Generated by Django 2.0.5 on 2018-09-27 10:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('doorAccess', '0008_auto_20180926_0824'),
    ]

    operations = [
        migrations.AlterField(
            model_name='nfcdoor',
            name='doorUUID',
            field=models.CharField(default='cyJPSmPOp8jePjmM', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='AESEncryptKey',
            field=models.CharField(default='Oxdz9fFLyFUg2Pzk', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='accesTrue',
            field=models.CharField(default='WYIRKWYcl7fbw7QmDh4b6I6AITRt5JPm', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='keyUTID',
            field=models.CharField(default='XUkD40nGjO76wWyM7rukKlNBozR4tPN8', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfckey',
            name='keyUUID',
            field=models.CharField(default='pcKJoTLRFi3f7Z0RFP2s', max_length=20),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='TDAT',
            field=models.CharField(default='UIgVPMtVQpz5Ex0y', max_length=32),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='accesingUDID',
            field=models.CharField(default='X0PbuI3baAtQHVBw', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='accessingUUID',
            field=models.CharField(default='VoOiV29', max_length=7),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='encryptionKey',
            field=models.CharField(default='mxBKI0Ifu8KG2VVA', max_length=16),
        ),
        migrations.AlterField(
            model_name='nfclistofusers',
            name='encryptionSalt',
            field=models.CharField(default='t2BEdDZf2flRKKak', max_length=16),
        ),
    ]