from datetime import timedelta
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404,render,redirect
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from .models import Device,AdvancedReview
from .security import audit,mfa_fresh
from .zenarmor_scope import digest,device_snapshot
from .advanced_coverage import snapshot
from .zenarmor_bypass import snapshot as bypass_snapshot
from .forms import ScopedModelForm

def revision(device):
    health=getattr(device,'health',None)
    engine=health.engines.get('Zenarmor',{}) if health else {}
    return digest({'vendor':device.vendor,'device':device.pk,'policies':engine.get('scope',{}).get('policy_fingerprint'),
        'interfaces':engine.get('scope',{}).get('interfaces'),'bypass':engine.get('bypass'),
        'local_bypass':bypass_snapshot(device).get('fingerprint')})

class ReviewForm(ScopedModelForm):
    class Meta:
        model=AdvancedReview;fields=['note','valid_until'];widgets={'note':forms.Textarea(attrs={'rows':4}),'valid_until':forms.DateTimeInput(format='%Y-%m-%dT%H:%M',attrs={'type':'datetime-local'})}
    def clean_note(self):
        value=self.cleaned_data['note'].strip()
        if len(value)<20:raise forms.ValidationError('Describe qué revisaste y la referencia de la comprobación, sin claves ni contraseñas.')
        return value
    def clean_valid_until(self):
        value=self.cleaned_data['valid_until']
        if not timezone.now()<value<=timezone.now()+timedelta(days=30):raise forms.ValidationError('Selecciona una vigencia futura de hasta treinta días.')
        return value

@login_required
@require_http_methods(['GET','POST'])
def advanced(request,pk):
    device=get_object_or_404(Device.objects.select_related('site__client'),pk=pk)
    form=ReviewForm(request.POST or None)
    if request.method=='POST':
        if not request.user.has_perm('core.manage_operations'):return HttpResponseForbidden()
        if not mfa_fresh(request):return redirect('mfa_challenge')
        if device.vendor!='opnsense' or not device.zenarmor_enabled:return HttpResponseForbidden()
        if request.POST.get('revision')!=revision(device):
            messages.error(request,'La configuración observada cambió. Revisa la página antes de guardar.');return redirect('advanced_coverage',pk=pk)
        if form.is_valid():
            row=form.save(commit=False);row.device=device;row.reviewed_by=request.user;row.baseline=revision(device);row.save()
            audit('coverage.manual_review',row,{'fields':['zenarmor_global_exemptions']})
            return redirect('advanced_coverage',pk=pk)
    review=device.advanced_reviews.order_by('-created_at').first()
    declared_current=bool(review and review.valid_until>timezone.now() and review.baseline==revision(device))
    catalog=getattr(device,'attribution_catalog',None)
    bypass=bypass_snapshot(device)
    nat={'current':bypass['current'],'checked_at':catalog.last_success_at if catalog else None,
        'rules':len(catalog.data.get('rules',[])) if catalog else 0,
        'unsupported':catalog.data.get('unsupported_rules',0) if catalog else 0,
        'disabled':catalog.data.get('disabled_rules',0) if catalog else 0}
    return render(request,'advanced_coverage.html',{'device':device,'advanced':snapshot(device),'zenarmor':device_snapshot(device),
        'review':review,'declared_current':declared_current,'form':form,'revision':revision(device),
        'bypass':bypass,'nat':nat})
