shared_examples "a scan result" do
  it "should have a raw result" do
    expect(subject.raw).not_to be_nil
  end
  it "should have a version" do
    expect(subject.version).not_to be_nil
  end
  it "should have a scanned_at time" do
    expect(subject.scanned_at).to be_a(Time)
  end
  it "should have a string representation" do
    expect(subject.to_s).not_to be_nil
  end
end

shared_examples "a successful scan result" do
  it "should not have a virus" do
    expect(subject.virus_found).to be_nil
    expect(subject).not_to have_virus
  end
  it "should not have an error" do
    expect(subject).not_to be_error
  end
  it "should be ok" do
    expect(subject).to be_ok
  end
end

shared_examples "an error scan result" do
  it "should have an error" do
    expect(subject).to be_error
  end
  it "shoud not have a virus" do
    expect(subject.virus_found).to be_nil
    expect(subject).not_to have_virus
  end
  it "should not be ok" do
    expect(subject).not_to be_ok
  end
end

shared_examples "a virus scan result" do
  it "shoud have a virus" do
    expect(subject.virus_found).not_to be_nil
    expect(subject).to have_virus
  end
  it "should not have an error" do
    expect(subject).not_to be_error
  end
  it "should not be ok" do
    expect(subject).not_to be_ok
  end
end
