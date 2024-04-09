package config

func createExternalMevStep(wiz *wizard, currentStep int, totalSteps int) *textBoxWizardStep {
	// Create the labels
	urlLabel := wiz.md.Config.MevBoost.ExternalUrl.Name

	helperText := "Please enter the URL of your external MEV-Boost client.\n\nFor example: `http://192.168.1.46:18550`"

	show := func(modal *textBoxModalLayout) {
		wiz.md.setPage(modal.page)
		modal.focus()
		for label, box := range modal.textboxes {
			for _, param := range wiz.md.Config.MevBoost.GetParameters() {
				if param.GetCommon().Name == label {
					box.SetText(param.String())
				}
			}
		}
	}

	done := func(text map[string]string) {
		wiz.md.Config.MevBoost.Enable.Value = true
		wiz.md.Config.MevBoost.ExternalUrl.Value = text[urlLabel]
		wiz.finishedModal.show()
	}

	back := func() {
		wiz.mevModeModal.show()
	}

	return newTextBoxWizardStep(
		wiz,
		currentStep,
		totalSteps,
		helperText,
		70,
		"MEV-Boost (External)",
		[]string{urlLabel},
		[]int{wiz.md.Config.MevBoost.ExternalUrl.MaxLength},
		[]string{wiz.md.Config.MevBoost.ExternalUrl.Regex},
		show,
		done,
		back,
		"step-external-mev",
	)
}
