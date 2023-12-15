class Rect {
  public:
    Rect() : width(0), height(0) {}
    int area() { return width*height; }
    virtual void set_vals(int w, int h);
  protected:
    int width;
    int height;
};

void Rect::set_vals(int w, int h)
{
  this->width = w;
  this->height = h;
}

class Square : public Rect {
  public:
    Square() : Rect() {}
    void set_vals(int l) { width = height = 1; }
};
