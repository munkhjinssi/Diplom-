from django import forms
from .models import ScannerHistory 

class ScannerForm(forms.Form):

    class Meta:
        model = ScannerHistory
        fields = [
            'target', 
            'type'
        ] 

    target = forms.CharField(
        required=True,
        max_length=20,
        min_length=7,
        strip=True, 
        label='Хостын хаяг',  
    )

    QUICK = 'QS'
    FULL = 'FS'
    type = forms.ChoiceField(  
        choices = (
            (QUICK, "Бүрэн шалгалт"),
            (FULL, "Хурдан шалгалт")
        ),
        widget = forms.RadioSelect(attrs={'class': 'form-control my-type'}),
        initial = 'QS', 
        label='Шалгалтын төрөл'
    ) 

    