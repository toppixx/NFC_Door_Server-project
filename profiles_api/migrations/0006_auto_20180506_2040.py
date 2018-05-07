# Generated by Django 2.0.5 on 2018-05-06 20:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('profiles_api', '0005_auto_20180505_1450'),
    ]

    operations = [
        migrations.CreateModel(
            name='DoorNfcGroupModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('group_name', models.CharField(max_length=30)),
                ('door_nfc_tag_list', models.TextField()),
            ],
        ),
        migrations.DeleteModel(
            name='DoorAccesControll',
        ),
        migrations.AddField(
            model_name='userprofile',
            name='nfc_tag_list_group',
            field=models.TextField(default=1),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='doornfctagmodel',
            name='door_nfc_tag',
            field=models.TextField(),
        ),
    ]
