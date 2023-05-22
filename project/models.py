from django.db import models   

 
class Host(models.Model):

    IP = models.GenericIPAddressField()

    mac_address = models.CharField(
        max_length=20,
        null=True
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

    class Meta:
        ordering = ['-created_on']

class OperativeSystemMatch(models.Model):

    name = models.CharField(
        max_length=255
    )

    accuracy = models.PositiveSmallIntegerField()

    line = models.PositiveSmallIntegerField()

    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name='host_os_match'
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

    class Meta:
        ordering = ['-created_on']

class OperativeSystemClass(models.Model):

    operative_system_match = models.OneToOneField(
        OperativeSystemMatch,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='os_match_class'
    )

    type = models.CharField(
        max_length=255
    )

    vendor = models.CharField(
        max_length=255
    )

    operative_system_family = models.CharField(
        max_length=255
    )

    operative_system_generation = models.CharField(
        max_length=255
    )

    accuracy = models.PositiveSmallIntegerField()

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

class Port(models.Model):

    protocol = models.CharField(
        max_length=255
    )

    portid = models.PositiveSmallIntegerField()

    state = models.CharField(
        max_length=255
    )

    reason = models.CharField(
        max_length=255
    )

    reason_ttl = models.PositiveSmallIntegerField()

    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name='host_port'
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

    class Meta:
        ordering = ['-created_on']

class PortService(models.Model):

    port = models.OneToOneField(
        Port,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='port_service'
    )

    name = models.CharField(
        max_length=255,
        null=True
    )

    product = models.CharField(
        max_length=255,
        null=True
    )

    extra_info = models.CharField(
        max_length=255,
        null=True
    )

    hostname = models.CharField(
        max_length=255,
        null=True
    )

    operative_system_type = models.CharField(
        max_length=255,
        null=True
    )

    method = models.CharField(
        max_length=255,
        null=True
    )

    conf = models.PositiveSmallIntegerField()

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

class ScannerHistory(models.Model):

    target = models.GenericIPAddressField()

    hosts = models.ManyToManyField(
        Host,
        related_name='host_history'
    )

    # Choices for field type
    QUICK = 'QS'
    FULL = 'FS'
    TYPE_CHOICES = [
        (QUICK, 'Quick scan'),
        (FULL, 'Full scan'),
    ]

    type = models.CharField(
        max_length=2,
        choices=TYPE_CHOICES,
        default=QUICK,
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

    class Meta:
        ordering = ['-id']  

class Whois(models.Model): 
    domain_name = models.CharField(max_length=255) 
    registrar = models.CharField(max_length=255,blank=True, null=True)   
    whois_server = models.CharField(max_length=255, blank=True, null=True)  
    referral_url = models.URLField(max_length=50,blank=True,null=True)
    name_server = models.TextField(blank=True,null=True)
    status = models.TextField(blank=True, null=True) 
    emails = models.EmailField(max_length=255, null=True)
    dnssec = models.CharField(max_length=255, blank=True, null=True) 
    name = models.CharField(max_length=255, blank=True, null=True) 
    org = models.CharField(max_length=255, blank=True, null=True) 
    address = models.TextField(blank=True, null=True) 
    city = models.CharField(max_length=50,blank=True, null=True) 
    state = models.CharField(max_length=50, blank=True, null=True) 
    registrant_postal_code = models.IntegerField(blank=True, null=True) 
    country = models.CharField(max_length=100,blank=True, null=True)
    created_date = models.DateTimeField(blank = True, null=True)  
    expiration_date = models.DateTimeField(blank=True, null=True)
    updated_date = models.DateTimeField(blank=True, null=True)   
     
    def __str__ (self):    
        return self.domain_name  
    
class IPData(models.Model):
    ip = models.CharField(max_length=45)
    status = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    countryCode = models.CharField(max_length=10)
    region = models.CharField(max_length=100)
    regionName = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    zip = models.CharField(max_length=20)
    lat = models.FloatField()
    lon = models.FloatField()
    timezone = models.CharField(max_length=100)
    isp = models.CharField(max_length=100)
    org = models.CharField(max_length=100)
    as_name = models.CharField(max_length=100)
    mobile = models.BooleanField(null=True)
    proxy = models.BooleanField(null=True)
    hosting = models.BooleanField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip 
    
class IPcreated(models.Model):  
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the ip geo was created"
    )



    
