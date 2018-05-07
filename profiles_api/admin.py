from django.contrib import admin
from . import models
from .models import DoorNfcTagModel

# Register your models here.
admin.site.register(models.UserProfile)
admin.site.register(models.DoorNfcListModel)
admin.site.register(models.DoorNfcTagModel)
admin.site.register(models.DoorNfcGroupModel)

#class FlatPageAdmin(admin.ModelAdmin):#
#    fieldsets=(#
#    (None,{
#    'fields' : ('url', 'titel', 'content', 'sites')}),
#    ('Advanced options' ,{'classes' : ('collapse',),
#    'fields' : ('registration_required', 'template_name'),
#    }),
#    )


#from django.contrib import admin
#from django.utils.translation import ugettext_lazy as _


#class FlatPageAdmin(admin.ModelAdmin):
#    fieldsets = (
#        (None, {'fields': ('door_name', 'door_nfc_tag_list')}),
#        (('Advanced options'), {
#            'classes': ('collapse', ),
#            'fields': ('door_name',
#                'door_:nfc_tag_list',
#            ),
#        }),
#    )
#    list_display = ['door_name', 'door_nfc_tag_list']
#    list_filter = ['door_name', 'door_nfc_tag_list']
#
#admin.site.register(DoorNfcTagModel, FlatPageAdmin)
